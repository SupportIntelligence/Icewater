
rule m3e9_3285ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3285ea48c0000b12"
     cluster="m3e9.3285ea48c0000b12"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob backdoor"
     md5_hashes="['03793c40ca93223aa1c458d9cfed96b5','1e317adefd2624ee31215dcf98610a3d','d25760de9595fd738f8da006b5585c30']"

   strings:
      $hex_string = { c76100ffc56000f3bb5b01d4b25702c49a4b04a6713808874f290b774e2810804b27259d4c4dbaff3d54dfff3436affd321c1ac7311e247e301d2b353322330f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
