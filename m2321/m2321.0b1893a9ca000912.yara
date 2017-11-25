
rule m2321_0b1893a9ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b1893a9ca000912"
     cluster="m2321.0b1893a9ca000912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="coinminer zusy maener"
     md5_hashes="['24f6437e596c6100871b2681b57b6f70','84c71c17815701650905979858138b37','f6dbc198fefb2f30dac343fb2c10c0d0']"

   strings:
      $hex_string = { 3bd423f59f9b41831cc7ed4778791b1260ecc3b8bf4d3a297f6413af51eba14bc44475ac320e463f8cfd5ba5d36ab3fc9149b42101e6e5df2a75f3f48bfaab16 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
