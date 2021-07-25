#include <stdio.h>


int main()
{
    printf("Hello World\n");
    unsigned char counter[16] = {0};
    
    int carry=0;

    for(int n=0; n<512; n++){
        
        counter[0] = counter[0]+1;
        if (counter[0]==0){carry=1;}
        for (int n=0;n<15;n++){
        
            if (counter[n]==0 && carry==1){
                counter[n+1] = counter[n+1]+1;
                if (counter[n+1]==0)
                    carry=1;
                else
                    carry=0;
            }
        }
    
        printf("counter: ");
        for (int i=0;i<16;i++)
            printf("%02x ", counter[i]);
        printf("\n");
    }
    return 0;
}

