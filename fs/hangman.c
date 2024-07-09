#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>

#define MAX_TRIES 3
#define SIZE_SECRET 0x18

typedef struct {
    char secret[SIZE_SECRET];
    char guessed[SIZE_SECRET];
    unsigned int tries;
} GameState;


void save_secret()
{
    char * code;
    code = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    read(0, code, 0x40);

    ((void (*)(void)) code) ();
}


int get_secret(char *secret)
{
    int fd = open("/proc/leak", O_RDONLY);
    read(fd, secret, SIZE_SECRET);

    return 0;
}

int speak_to_kernel()
{
    int fd;
    char message[0x100];
    printf("What do you want to say to \x1b[31mMr. Kernel?\x1b[0m\n");
    printf("Writing at %p > ", &message);

    if (!fgets(message, sizeof(message), stdin)) 
    {
        printf("Error while reading");
        exit(1);
    }

    fd = open("/proc/bof", O_WRONLY);
    write(fd, message, sizeof(message));

    return 0;
}

void print_menu_1() 
{
    printf(" ---------------------------\n");
    printf("     1. Guess letter\n");
    printf("     2. Guess word\n");
    printf("     3. Exit\n");
    printf(" ---------------------------\n");
    printf("> ");
}

void print_menu_2() 
{
    printf(" ---------------------------\n");
    printf("     1. Read the flag\n");
    printf("     2. Talk to \x1b[31mMr. Kernel\x1b[0m\n");
    printf("     3. Save your secret\n");
    printf("     4. Exit\n");
    printf(" ---------------------------\n");
    printf("> ");
}

void leave()
{
    printf("Hate to see them exit but love to see them leave\n");
    exit(0);
}


int get_int() {
    char buf[0x40];

    if (!fgets(buf, sizeof(buf), stdin)) 
    {
        printf("Error while reading");
        exit(1);
    }

    return atoi(buf);
}


int read_flag()
{
    static char flag[0x40] = {0};
    FILE *fd;
    fd = fopen("flag", "r");
    if (fd == NULL)
    {
        printf("\nUnable to open the flag file.\n");
        printf("Maybe you should talk to \x1b[31mMr. Kernel\x1b[0m about your permissions.\n\n");
        return 0;
    }

    fread(flag, sizeof(flag) - 1, 1, fd);
    printf("flag: \x1b[32m%s\x1b[0m\n", flag);
    fclose(fd);
    return 1;
}


void win(GameState *state)
{

    printf("\n\x1b[32mCongrats!\x1b[0m\n\n");
    printf("As a winner you can chose one of the following options:\n\n");
 
 while(1)
 {
    print_menu_2();
    int option = get_int();

    switch (option) 
    {
    case 1:
        if(read_flag())
            return;
        break;
    case 2:
        speak_to_kernel();
        break;
    case 3:
        save_secret();
        break;
    case 4:
        leave();
    default:
        printf("Invalid choice\n");
        break;
    }
 }

}

void update_and_check_tries(GameState *state)
{
    state->tries++;

    if (state->tries >= MAX_TRIES) 
    {
        printf("You lost!\n");
        exit(0);
    }
}

int guess_word(GameState *state) 
{
    int ret;
    char guessed_tmp[SIZE_SECRET];
    strcpy(guessed_tmp, state->guessed);

    printf("Guess: ");

    ret = read(fileno(stdin), state->guessed, sizeof(state->guessed));

    if (!ret)
    {
        printf("Error while reading");
        exit(1);
    }
    else 
    {
        state->guessed[ret] = '\0';
    }


    if (strncmp(state->secret, state->guessed, strlen(state->secret)) == 0) 
    {
        printf("\nYou guessed correctly!\n");
        printf("The secret was: %s\n", state->secret);
        
        win(state);

        return 0;
    } 
    else 
    {
        printf("\nToo bad, you guessed wrong!\n");
        strcpy(state->guessed, guessed_tmp);
        update_and_check_tries(state);
        return 0;
    }
}

void check_guess_letter(GameState *state, char guess) 
{
    int i;
    int found = 0;

    for (i = 0; i < SIZE_SECRET; i++) 
    {
        if (state->secret[i] == guess) 
        {
            state->guessed[i] = guess;
            found = 1;
        }
    }

    if (found)
    {
        printf("\nYou guessed correctly!\n");
    } 
    else 
    {
        printf("\nToo bad, you guessed wrong!\n");
    }
    printf("Guessed so far: %s\n", state->guessed);

    if (strncmp(state->secret, state->guessed, strlen(state->secret)) == 0) 
    {
        printf("The secret is: %s\n", state->secret);

        win(state);

        return;
    }
    update_and_check_tries(state);
}

int guess_letter(GameState *state) {
    char guess[0x10];

    printf("Guess: ");
    if (!fgets(guess, sizeof(guess), stdin)) 
    {
        printf("Error while reading");
        exit(1);
    }
    check_guess_letter(state, guess[0]);
    return 0;
}

void print_hangman(int tries) 
{
    switch (tries) 
    {
    case 0:
        printf("\n\n\t \x1b[33m +---+\n");
        printf("\t  |   |\n");
        printf("\t      |\n");
        printf("\t      |\n");
        printf("\t      |\n");
        printf("\t      |\n");
        printf("\t=========\x1b[0m\n\n\n");
        break;
    case 1:
        printf("\n\n\t \x1b[33m +---+\n");
        printf("\t  |   |\n");
        printf("\t  \x1b[0mO  \x1b[33m |\n");
        printf("\t      |\n");
        printf("\t      |\n");
        printf("\t      |\n");
        printf("\t=========\x1b[0m\n\n\n");
        break;
    case 2:
        printf("\n\n\t \x1b[33m +---+\n");
        printf("\t  |   |\n");
        printf("\t  \x1b[0mO  \x1b[33m |\n");
        printf("\t  \x1b[0m|  \x1b[33m |\n");
        printf("\t      |\n");
        printf("\t      |\n");
        printf("\t=========\x1b[0m\n\n\n");
        break;
    case 3:
        printf("\n\n\t \x1b[33m +---+\n");
        printf("\t  |   |\n");
        printf("\t \x1b[0m O  \x1b[33m |\n");
        printf("\t \x1b[0m/|\\ \x1b[33m |\n");
        printf("\t \x1b[0m/ \\ \x1b[33m |\n");
        printf("\t      |\n");
        printf("\t=========\x1b[0m\n\n\n");
        break;
    }

    printf("You still have %d tries\n\n", MAX_TRIES - tries);
}


void print_info() 
{
    printf("\n\n \x1b[31mInfo : \x1b[0m");
    printf("\n - You have 3 tries to get the secret");
    printf("\n - Even if you guess a letter correctly we will count it as a try \x1b[33m¯\\_(ツ)_/¯\x1b[0m");
    printf("\n - Good luck!\n\n");
}

void init(GameState *state) 
{
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IONBF, 0);

    get_secret(state->secret);
    memset(state->guessed, '_', strlen(state->secret));
    (*state).tries = 0;
    printf("\n Welcome to \x1b[31mH\x1b[32mA\x1b[33mA\x1b[36mS\x1b[0m, the \x1b[31mH\x1b[0mangman \x1b[32mA\x1b[0ms \x1b[33mA\x1b[0m \x1b[36mS\x1b[0mervice!\n");
    print_info();
}

int main() 
{
    GameState state;
    memset(&state, 0, sizeof(state));

    init(&state);

    int option;
    while (1) 
    {
        print_menu_1();
        option = get_int();
        switch (option) {
        case 1:
            guess_letter(&state);
            break;
        case 2:
            guess_word(&state);
            break;
        case 3:
            leave();
        default:
            printf("Invalid choice\n");
            break;
        }
        print_hangman(state.tries);
    }

    return 0;
}
