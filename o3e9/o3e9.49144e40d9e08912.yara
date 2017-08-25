import "hash"

rule o3e9_49144e40d9e08912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.49144e40d9e08912"
     cluster="o3e9.49144e40d9e08912"
     cluster_size="2662 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="graftor noobyprotect malicious"
     md5_hashes="['04a39686f4298deae62b491924bc13b5', '1028f7045eb56052c042519202979670', '0bae24c750719a2a23673ee348e14421']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3116032,1024) == "158f26e6bba485ef0680fe8a8d655bcc"
}

