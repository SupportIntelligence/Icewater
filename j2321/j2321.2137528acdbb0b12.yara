
rule j2321_2137528acdbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.2137528acdbb0b12"
     cluster="j2321.2137528acdbb0b12"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre generickd trojandownloader"
     md5_hashes="['188b4f37c63255997aa577a689f253dc','5d7270c1926a5da172d3ffce6da22d75','fd0486d69cf59d093c03d826d906aa24']"

   strings:
      $hex_string = { 90fd8a027518d067294c8ff7caba28b5dc421ee1e474dc483f07eb66934f59b022b384961dac683a27230cb95f234535c5e2b98167d4a91160eaf1ec70f83447 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
