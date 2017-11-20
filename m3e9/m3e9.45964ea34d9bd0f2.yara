
rule m3e9_45964ea34d9bd0f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.45964ea34d9bd0f2"
     cluster="m3e9.45964ea34d9bd0f2"
     cluster_size="54"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['153a7a9ae695dec93fbda7741a6cdf4b','2344dc90a5c98a1cf036972e42da7654','a4f30c10eff88e7d2bb13421e72f1420']"

   strings:
      $hex_string = { 8b0af6c102750883c90233c0890a404683c20c3b3772e93bc374115353535753ff75fcff150c1000018945f0395df07507c745f40310048057e8d885feff59eb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
