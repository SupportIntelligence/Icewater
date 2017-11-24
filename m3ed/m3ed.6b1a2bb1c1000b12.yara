
rule m3ed_6b1a2bb1c1000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.6b1a2bb1c1000b12"
     cluster="m3ed.6b1a2bb1c1000b12"
     cluster_size="252"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit backdoor nimnul"
     md5_hashes="['02e356346d89f10b9c9813c34239aae2','033923117d2ba1a67c7cf8ce9a7e603d','0cadd2cf9abad8380a6ca6d35af19bd0']"

   strings:
      $hex_string = { 403bc672be8b4dfc5ee8b3a3ffffc9c3558bec83ec1ca1f481011053568b750833db3bf38945fc570f845401000033d233c039b0688a0110746583c030423df0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
