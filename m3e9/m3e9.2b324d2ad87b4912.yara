
rule m3e9_2b324d2ad87b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b324d2ad87b4912"
     cluster="m3e9.2b324d2ad87b4912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod jaike trojandropper"
     md5_hashes="['231066110e883561c492fd8177afcdde','4632a1069c6fa9405c0a0d27beffaecf','b6bf331adfd664b49ab985c95fe5c589']"

   strings:
      $hex_string = { 6a3b520c74f3bc9b675dc0838b9297b748887b69fe65135e6c090b8ce027c60570bdbaf8fa60449046dc991fa5f67d5c38b55d2d37eed06b93357ff2f04ede79 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
