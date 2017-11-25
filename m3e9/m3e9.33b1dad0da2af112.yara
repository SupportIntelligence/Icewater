
rule m3e9_33b1dad0da2af112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33b1dad0da2af112"
     cluster="m3e9.33b1dad0da2af112"
     cluster_size="306"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ckef delf malicious"
     md5_hashes="['013f38ceea69c16032a57e3edf0e0616','01419df7bbf7abe5add7aa3e6e4dde68','0c71130f59c090e5ae3607dc2d13145e']"

   strings:
      $hex_string = { e2ee66bb1a9b0c3d25a8b51683c04089dc83286976866708178412d91f44702738555d1831bab9111e46530b1423573f8fedd80536857c7d75490d203b45c4ec }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
