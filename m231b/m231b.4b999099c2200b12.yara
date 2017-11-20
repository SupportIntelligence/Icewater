
rule m231b_4b999099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.4b999099c2200b12"
     cluster="m231b.4b999099c2200b12"
     cluster_size="11"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['2332a5f283ff0db6827f867c59b9f720','5c10e7103b395f217a40212c6f508b3c','ff8a4fce053eb962728ac1d002644da8']"

   strings:
      $hex_string = { 39303238313643343433464641413944383146373233343944453643313937353932463643423731413541353830364244304531353432334536373632303835 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
