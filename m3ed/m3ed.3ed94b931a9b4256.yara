
rule m3ed_3ed94b931a9b4256
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3ed94b931a9b4256"
     cluster="m3ed.3ed94b931a9b4256"
     cluster_size="346"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy quchispy backdoor"
     md5_hashes="['002904776f9614ef0e61e87e66429cf5','016abec6b2be6b50c641005829e635f7','15f31417f01509d6d15489d1a887ab6b']"

   strings:
      $hex_string = { 00011890c60feee0c139b4cf095c78c52be6f7440e4cc293fcfba11520600d0568e22a10b087022071150ca8628cd258e00766f98138c41213b3e480142c11be }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
