
rule m3e7_1a599799c2200b40
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.1a599799c2200b40"
     cluster="m3e7.1a599799c2200b40"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shodi virut shohdi"
     md5_hashes="['1985adb469fa96f386a5bdd398b93367','1d404e7e6887e9cdf8e5332e2b126447','d0148ff520b87a8c4aa11adae9324f8c']"

   strings:
      $hex_string = { 85db7c128039357c0deb03c600304880383974f7fe00803e317505ff4204eb1a8bc78d50018a084084c975f92bc240505756e8d9faffff83c40c5f5e5b5dc355 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
