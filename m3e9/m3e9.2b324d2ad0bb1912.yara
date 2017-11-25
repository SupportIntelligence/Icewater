
rule m3e9_2b324d2ad0bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b324d2ad0bb1912"
     cluster="m3e9.2b324d2ad0bb1912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod jaike trojandropper"
     md5_hashes="['0ded0e3e47588b02fbfb140149766608','75a20f6b3fbcbfc6f7fbdb4648ad214e','cd1528af1c9c62862304ea76f31967f8']"

   strings:
      $hex_string = { 6a3b520c74f3bc9b675dc0838b9297b748887b69fe65135e6c090b8ce027c60570bdbaf8fa60449046dc991fa5f67d5c38b55d2d37eed06b93357ff2f04ede79 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
