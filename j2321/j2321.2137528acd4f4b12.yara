
rule j2321_2137528acd4f4b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.2137528acd4f4b12"
     cluster="j2321.2137528acd4f4b12"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader generickd"
     md5_hashes="['4c29e4005a5d73e8a20f3ec6af471042','631c09442e90f49a5e8c3eff73376c70','efb77efc433fc6d54c88f3b5869d3876']"

   strings:
      $hex_string = { 90fd8a027518d067294c8ff7caba28b5dc421ee1e474dc483f07eb66934f59b022b384961dac683a27230cb95f234535c5e2b98167d4a91160eaf1ec70f83447 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
