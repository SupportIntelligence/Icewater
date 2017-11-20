
rule k3e9_193e6de159b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.193e6de159b2f316"
     cluster="k3e9.193e6de159b2f316"
     cluster_size="518"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted click"
     md5_hashes="['005b00f6d98805e73dc59d0e3c3d9407','015395bffc7d8af2cd9130da2e8bf36e','0880402805921cebaa1e1c794bdfd1eb']"

   strings:
      $hex_string = { 9c0906f0fb78a95c8bbc6788e04e3087f994db49c25315381958ba758c2f80af22771f47656bd21ac1a7e2523ff776ccd834c0541bd544f52440339914212ace }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
