
rule k3e9_1b1c68988ba10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c68988ba10b16"
     cluster="k3e9.1b1c68988ba10b16"
     cluster_size="51"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp apanas"
     md5_hashes="['073492c9c29686fc50a041a1c723f658','0ab3fdb8df3d1bcc330f512648887893','6a2814de20994d36f34155d12d6e3164']"

   strings:
      $hex_string = { 022c208a57ff88d480ec6180fc19770380ea20b40029d0750580fa0075d25e5fc38d4000979283c9ff31c039f87406f2ae484829c889d7c356e83afbffff89d6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
