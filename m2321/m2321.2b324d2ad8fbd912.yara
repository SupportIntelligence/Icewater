
rule m2321_2b324d2ad8fbd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b324d2ad8fbd912"
     cluster="m2321.2b324d2ad8fbd912"
     cluster_size="50"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod jaike trojandropper"
     md5_hashes="['17755180c0ee85a8cae0303698f6a774','2013cee053538b8246b3bf99f9f1dc84','58f647acd58fa0dbd5237d19ca062a91']"

   strings:
      $hex_string = { 6a3b520c74f3bc9b675dc0838b9297b748887b69fe65135e6c090b8ce027c60570bdbaf8fa60449046dc991fa5f67d5c38b55d2d37eed06b93357ff2f04ede79 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
