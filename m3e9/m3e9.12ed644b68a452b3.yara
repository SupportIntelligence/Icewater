
rule m3e9_12ed644b68a452b3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.12ed644b68a452b3"
     cluster="m3e9.12ed644b68a452b3"
     cluster_size="17"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cpsg riskware adload"
     md5_hashes="['025581413417d1489f6a489573a24d53','08f1cdcc84b01e8ef37c71dfbc65a586','f2c946946cd65f29a5e28346a05286ea']"

   strings:
      $hex_string = { 54b1050e02b67c0432203c68e888a08abec9d9e4eba7f85fe908b253d2ed8b480337c4bb19a9110fd53e967949281c69b492da971ebc4ccdf2f96c8589571da2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
