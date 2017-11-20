
rule m3e9_09c91299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.09c91299c2200b12"
     cluster="m3e9.09c91299c2200b12"
     cluster_size="24"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy androm backdoor"
     md5_hashes="['087b6d930d15e8fe1d723c58c49ec802','10beaaeae596a9ff6b24658c8c4a9658','bb63a925a43ac971de995f6070764fd9']"

   strings:
      $hex_string = { ebda8bd18a06880242463ac374034f75f33bfb75108819e8dff6ffff6a225989088bf1ebc133c05f5e5b5dc38bff558bec8b4d085633f63bce7c1e83f9027e0c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
