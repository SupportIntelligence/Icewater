
rule m3e9_3a4d12d18cbb0b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a4d12d18cbb0b16"
     cluster="m3e9.3a4d12d18cbb0b16"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro kakavex malicious"
     md5_hashes="['a1e50d719c4d217499fd980742eed062','b62d71f69fd948cc71d4de24464adfa0','e2614b5c83e19d50fb69fa6418abfd75']"

   strings:
      $hex_string = { 69071d150a3c3b3b2c273d1f2c3b3a20262700090077270518130214033e1300290089dac6cfdddec8dbccd5c4e0eafbe6fae6effdd5dee0e7ede6fefad5cafc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
