
rule o3f1_5169b841c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.5169b841c8000932"
     cluster="o3f1.5169b841c8000932"
     cluster_size="641"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hiddad androidos mobidash"
     md5_hashes="['006e60fa239f3a9dde56cf829640159f','008552463da44041260017fb2c6e7362','06c6729b15eade38e490473a4421b5cd']"

   strings:
      $hex_string = { ffffffffffffff10000300be020000cb00087f03000000c700017f0800000501180000c800017f08000005213daa01cb00017f08000005217a54090202100024 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
