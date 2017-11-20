
rule m2321_11915366c91af916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.11915366c91af916"
     cluster="m2321.11915366c91af916"
     cluster_size="17"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy scudy"
     md5_hashes="['056e552d1a31fe531f42b42807823cb2','0fecc5ee3bc458e978f490d165f6f8f2','f8879a5e88e1059db3a307e19a85339e']"

   strings:
      $hex_string = { c751fc633cd02b5c2f809c1000afad760136a749c618e065bb8cc01e42f52e2092cff3db5ff9f2d53f503e0afd892224403964f7910713b47f1922795ba37260 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
