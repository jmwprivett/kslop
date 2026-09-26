#import <Foundation/Foundation.h>

#import "vphoned_install.h"

int main(int argc, char **argv)
{
    @autoreleasepool {
        if (argc != 2 && argc != 3) {
            fprintf(stderr, "usage: %s IPA [CERTIFICATE]\n", argv[0]);
            return 2;
        }
        NSString *package = [NSString stringWithUTF8String:argv[1]];
        NSMutableDictionary *request = [@{
            @"id": @"cnd-lab-install",
            @"path": package,
            @"registration": @"User",
        } mutableCopy];
        if (argc == 3) {
            request[@"cert_path"] = [NSString stringWithUTF8String:argv[2]];
        }
        NSDictionary *response = vp_handle_custom_install(request);
        NSData *encoded = [NSJSONSerialization dataWithJSONObject:response
                                                          options:0
                                                            error:nil];
        if (encoded) {
            fwrite(encoded.bytes, 1, encoded.length, stdout);
            fputc('\n', stdout);
        }
        return [response[@"t"] isEqualToString:@"ok"] ? 0 : 1;
    }
}
