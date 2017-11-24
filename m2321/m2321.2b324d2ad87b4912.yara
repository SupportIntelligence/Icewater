
rule m2321_2b324d2ad87b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b324d2ad87b4912"
     cluster="m2321.2b324d2ad87b4912"
     cluster_size="79"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod jaike trojandropper"
     md5_hashes="['015087d31603ff07e07e8a4d0ddc9ae4','03ca375b7a47a10b10bcf0db5cc1c3c1','2b94ff0485fa5c66dd21a17f24ab9e3f']"

   strings:
      $hex_string = { 6a3b520c74f3bc9b675dc0838b9297b748887b69fe65135e6c090b8ce027c60570bdbaf8fa60449046dc991fa5f67d5c38b55d2d37eed06b93357ff2f04ede79 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
