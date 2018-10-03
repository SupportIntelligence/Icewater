
rule n26d5_5db06936d7cb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.5db06936d7cb1912"
     cluster="n26d5.5db06936d7cb1912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious crypt"
     md5_hashes="['c2ddd901addb80931e00c7fcf387b2bfdb8a7c88','3d7781bbf52d39acf7ff441a5296efb240c1dffd','76c2ff8186300a841187fe306ace960b193978a5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.5db06936d7cb1912"

   strings:
      $hex_string = { 977cc135d70adba190136018f7721f5329a59452c669d91a719e7aeaa9e7149f7094abae8d91a2f012a098b9cc63163399423f436d76f2194738cc416ab8ecda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
