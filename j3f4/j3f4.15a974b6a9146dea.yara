
rule j3f4_15a974b6a9146dea
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.15a974b6a9146dea"
     cluster="j3f4.15a974b6a9146dea"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy atraps backdoor"
     md5_hashes="['15358fd5404dd0ccaf79eb43797c1622','225af7eb8bdf1c08659d96ac84251a8a','9951c4eb6faae09b07c747db82642275']"

   strings:
      $hex_string = { 496e666f0053797374656d2e57696e646f77732e466f726d73004170706c69636174696f6e006765745f45786563757461626c65506174680054687265616453 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
