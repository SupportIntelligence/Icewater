
rule k2321_0965b922d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0965b922d9eb1912"
     cluster="k2321.0965b922d9eb1912"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['2b622278f55d2c46b26828a9dd524ac0','46602f575d74c31350fdfc4f5e17d895','f327d268e2b5ef94dc7374fa4022d0fa']"

   strings:
      $hex_string = { aa4d3e465a18174a67e6a5a6d6a23d29e6be1f3802a460530ff1693cfa14bb1cc34b83a498baf2106dc8e27c1d2bda908d850bf69499f96bb18f162754950c9a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
