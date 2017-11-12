
rule n3e9_4116bcc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4116bcc1cc000b12"
     cluster="n3e9.4116bcc1cc000b12"
     cluster_size="2285"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chinky vobfus diple"
     md5_hashes="['006971b1e9796c68085cff2a111075bc','009d6ee8b0bf282c316890bec4583a70','05299760937f3297123f5b7943046525']"

   strings:
      $hex_string = { 006fa9c10070b4c80077b1cc0071b8d000838380008484820086868400898985008b8c88008c8c89008e8e8c009d808d0091918f009596920098999300989995 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
