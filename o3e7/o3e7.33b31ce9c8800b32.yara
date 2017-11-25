
rule o3e7_33b31ce9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.33b31ce9c8800b32"
     cluster="o3e7.33b31ce9c8800b32"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr malicious banker"
     md5_hashes="['35dd4028bb57b17ae5e0f00cf203b967','6baff55bd950b06f3784a30b39341d92','7b994a0133a3ddba2910a5c59c755880']"

   strings:
      $hex_string = { d5a6cfff491f78c2d340a3149bc516abb3ef3d41e08ce980c947ba93a841aa17e67f2ba116b612426b5527398df770e07c4230c93ce3ff96528ae7428edef99d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
