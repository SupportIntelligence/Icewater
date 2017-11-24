
rule m3e9_16c339170952f914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16c339170952f914"
     cluster="m3e9.16c339170952f914"
     cluster_size="999"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup zbot honret"
     md5_hashes="['00449522c6da6e841ace7995a94c78e5','0069e9445d5019f3137d5a3c607382d7','0a4ca063ed7bac458e37cd4c9bdc0309']"

   strings:
      $hex_string = { 7da3b8ea7ca2b703e6203a80e2243e84dee83188baec358cd6f02990d2f42d94cef82198aafc259cc6001aa0c2041ea4bec811a85acc15acf6cf09b0f2d30db4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
