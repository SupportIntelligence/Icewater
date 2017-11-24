
rule m3e9_33b1dad0da22f112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33b1dad0da22f112"
     cluster="m3e9.33b1dad0da22f112"
     cluster_size="313"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ckef delf malicious"
     md5_hashes="['0008e6631528ab083d7cd1d48ddb8fc4','001a12a13916f683ef529099f70c53be','08a07526028cdc6e88e3c321d622496b']"

   strings:
      $hex_string = { e2ee66bb1a9b0c3d25a8b51683c04089dc83286976866708178412d91f44702738555d1831bab9111e46530b1423573f8fedd80536857c7d75490d203b45c4ec }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
