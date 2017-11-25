
rule m3f9_06c26a0080000108
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.06c26a0080000108"
     cluster="m3f9.06c26a0080000108"
     cluster_size="4807"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kolabc malicious dcom"
     md5_hashes="['0003188150859381eea074c517aca3cf','00065802de07c4faf61edfdc6e783969','0049590730d484cbd7ddbb32b47063f3']"

   strings:
      $hex_string = { 5ff1be7a92c4842a4003373cd6000e34b85464a3281297a45674bb44d0030111cd709cf4e4d7b5b44c63d214a0e22fb2988038731bb2864d517710360a29b096 }

   condition:
      
      filesize > 16777216 and filesize < 67108864
      and $hex_string
}
