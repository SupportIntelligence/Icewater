
rule o3e9_3b1108968c4a73d2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.3b1108968c4a73d2"
     cluster="o3e9.3b1108968c4a73d2"
     cluster_size="837"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['0009fd6c1337942f2eb9204a31385b50','00116121cce3a7205e469141466530a9','0438c07ff35671e9fb7381db610877ca']"

   strings:
      $hex_string = { 945a1c667ff97dc27ed5784471dc40e9528414e91dc019caf3af281f6b9d28c85a1d9d200ed8d7d11c9cbec5dc5a1e356d212ded0f08de58cfca4c9b4280441c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
