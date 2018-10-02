
rule k26c9_61369fa1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c9.61369fa1c2000932"
     cluster="k26c9.61369fa1c2000932"
     cluster_size="73"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="democry malicious ransom"
     md5_hashes="['b1a4d5a7bbe5308185fb9acc1605bc29ad236f5f','c361050a8796b7c49807328b2b5fe45921b14e2a','8476f5eb19bb0ac64fd0eaee9ce12cd04c8bef1a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c9.61369fa1c2000932"

   strings:
      $hex_string = { 44202bf97815ffc283fa0f76ec85ff7e1a85f674064183fb01741083c8ff4883c478415e415d5f5e5d5bc34c8964247066896c2442488bcd4c897c2468ba0e00 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
