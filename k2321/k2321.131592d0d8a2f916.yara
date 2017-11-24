
rule k2321_131592d0d8a2f916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.131592d0d8a2f916"
     cluster="k2321.131592d0d8a2f916"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['0eb016bafdde73e0c1867fc820268c0d','2550b2c5ddb0ecaa0129ad4ac0c01d53','edca1356fa67a90cb2f21a8b73bf885a']"

   strings:
      $hex_string = { 0384074a09368ab95f887829999a42ebcba475cd7c1c80b26f70242e64221231ab93f85cfc4c9674271b9b45c94d04bed5d454eadc90a939225dac3b1365dd79 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
