
rule n3ed_63141ae992c31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.63141ae992c31932"
     cluster="n3ed.63141ae992c31932"
     cluster_size="331"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox graftor razy"
     md5_hashes="['002ebfd0e9472152db3bebca3b85f3c0','03f1e238d9baa4b135326a168aef87c0','105b1c67dd66eecfc095e7d46c5396c4']"

   strings:
      $hex_string = { 01400000636d70736400000000000000000000000020111200201212000000000080000000fc000000100a000010140000000000020000000110000074657374 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
