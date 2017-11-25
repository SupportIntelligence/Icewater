
rule m3e9_411c3ac1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c3ac1cc000b16"
     cluster="m3e9.411c3ac1cc000b16"
     cluster_size="173"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['00bbb7491849df773c0578d88779d18c','02a8560c7af50c75844037c33b878aa6','2bb0f8c27fb0f0bb3321a044fe894ce7']"

   strings:
      $hex_string = { 494f36c822410fbafb33e8acd425c19ead179a90860973825ffb4b7438ed246611dffd58ead1d64ac3c3af3c9cb5882e75a761204e993a12278b1304007decf6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
