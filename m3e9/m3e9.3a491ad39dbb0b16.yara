
rule m3e9_3a491ad39dbb0b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a491ad39dbb0b16"
     cluster="m3e9.3a491ad39dbb0b16"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro kakavex malicious"
     md5_hashes="['a4b4437eda8806c4857bfc0fbd3e1a91','b9512d4ac1f415ee0b00a5b31eb927a2','ff3883be452fa9fa952f4200700530b6']"

   strings:
      $hex_string = { 69071d150a3c3b3b2c273d1f2c3b3a20262700090077270518130214033e1300290089dac6cfdddec8dbccd5c4e0eafbe6fae6effdd5dee0e7ede6fefad5cafc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
