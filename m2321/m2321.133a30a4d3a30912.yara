
rule m2321_133a30a4d3a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.133a30a4d3a30912"
     cluster="m2321.133a30a4d3a30912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz banker"
     md5_hashes="['264acab4338acbdc9d627cb85e561161','6bdced00d35e957fbf9d35e5ed904e1b','fd44f236f81dfc66977f8b611430fe47']"

   strings:
      $hex_string = { a201e5eb814660e6531812a90d45e9573d86beec5a9ad53a77b4532b836aa6738de202258bdb0b8719fd4b3c8231dd7c952f0867b791e4caf4c6fb11099b2daa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
