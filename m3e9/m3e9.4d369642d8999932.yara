
rule m3e9_4d369642d8999932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4d369642d8999932"
     cluster="m3e9.4d369642d8999932"
     cluster_size="500"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zegost backdoor malob"
     md5_hashes="['00783a02b25056b6544b3362f686ff5c','02dcb8c9fea7d20aaf717346547a336d','133c75e15c024dee8302cb0fbfa7b1f1']"

   strings:
      $hex_string = { d635444865862124be839a5eb56d95f0f95b5f56a83e3af39f13e3199dbcab271e38e754e8dd91251b7cea4e10b2bb7aa431d77f84624f72d3dbb482874d1ab1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
