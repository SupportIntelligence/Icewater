
rule m3e7_1a707a1f46220b40
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.1a707a1f46220b40"
     cluster="m3e7.1a707a1f46220b40"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut prepender shodi"
     md5_hashes="['15692f5adde6ec08e68c56bf1106ff9a','1b88091e5636d8f36b2e3248a8218068','bac95562fd9241c92cd19375318ddbdf']"

   strings:
      $hex_string = { 2bd08a08880c024084c975f68b45088d50018a084084c975f98d4df8512bc28d4dfc5183c030508d85f8fbffff506a02ff35285f0001c745f804000000e8ce0f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
