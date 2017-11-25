
rule m3f4_2504692ce36732b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f4.2504692ce36732b2"
     cluster="m3f4.2504692ce36732b2"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor malicious"
     md5_hashes="['7bf7a5c2b3f5d498374f7032b1d8d352','aae57a178d6b539db326c65f2cf4d6d2','d8fedd438922c94add8ebb15f64af60d']"

   strings:
      $hex_string = { 680400003a003c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d3822207374616e64616c6f6e653d22796573223f3e0d0a3c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
