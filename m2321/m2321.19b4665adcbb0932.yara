
rule m2321_19b4665adcbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.19b4665adcbb0932"
     cluster="m2321.19b4665adcbb0932"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob shiz"
     md5_hashes="['1a53585073cdbcfe32f9f37d779b764a','6d66d800c47a021ad33bdf18f9966c30','7cd9242002a3c89fee9150cfaef6bdec']"

   strings:
      $hex_string = { 4cb103e6d1ea62078aad9dffd56eb7d7327600342d73ec4071baf47ed3b6e90c13427ff25d537c95e2f96b02c37545f66743d857096d5061985af8ebd9a0c4bd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
