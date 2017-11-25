
rule m3e9_0b915366db12d115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b915366db12d115"
     cluster="m3e9.0b915366db12d115"
     cluster_size="58"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar scudy zusy"
     md5_hashes="['01c50e9f0281dba76ac2c9f61cebeb89','0ece8b5e050e8055e970cdb529fff96a','4be8e4cb21e2f054e4ad77e0e8a2578a']"

   strings:
      $hex_string = { fb7dbc92c0aef8f4df095c4d95dc36c6aa5706747f82b56d8ec2d8ac689f841a71e6c93e53cad7b96be78d5f913ba672703d837ba9bc10faed7ecf3fe3cb0562 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
