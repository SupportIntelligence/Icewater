
rule m2321_0b1893a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b1893a9ca000b12"
     cluster="m2321.0b1893a9ca000b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="coinminer zusy maener"
     md5_hashes="['8f6b208b06dbee584e9bf9697c510fbc','94167784790206affc4762c6dfe4759b','e4a31063928ccea0b3f871ef74ca08f5']"

   strings:
      $hex_string = { 3bd423f59f9b41831cc7ed4778791b1260ecc3b8bf4d3a297f6413af51eba14bc44475ac320e463f8cfd5ba5d36ab3fc9149b42101e6e5df2a75f3f48bfaab16 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
