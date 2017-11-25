
rule o3e9_6b9d6a48c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6b9d6a48c0000b16"
     cluster="o3e9.6b9d6a48c0000b16"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur malicious"
     md5_hashes="['063ee65f2e68b73a109302e4bf061613','0801a38b056b2f26ef9e82ab9ab46c8d','ae96eb88865b00d872290f6faf184565']"

   strings:
      $hex_string = { b3b3b3ffe6e5e5fff3fcfdff90def2ff43ccf1ff49caebff06c1f2ff14a1c7ff9f7c51fffeb456fffdc988fffee8d1fffeccacff976b68ff0000008f0202022f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
