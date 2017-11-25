
rule o3e9_4986b4cbde630b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4986b4cbde630b32"
     cluster="o3e9.4986b4cbde630b32"
     cluster_size="40"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['007396878ac8e9a2864b9b81b4cae227','0877de3c180d4214493556344f7f16c2','54c957b0e23d50e107398fdce7a1d770']"

   strings:
      $hex_string = { 002800250064002900110049006e00760061006c0069006400200063006f00640065002000700061006700650008004600650062007200750061007200790005 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
