
rule n3fd_0852892c5ba30914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fd.0852892c5ba30914"
     cluster="n3fd.0852892c5ba30914"
     cluster_size="1599"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo advml"
     md5_hashes="['00334babfa6cf98af08214a04eff9033','003473ae35d6258a4115f3b3a9fbbbca','02bd0b7fecb0f0472db12091ca8ad800']"

   strings:
      $hex_string = { 16577261704e6f6e457863657074696f6e5468726f77730102130007151281d9011e000407020e080500001280f1170705151280b1010e151280b1010e0e1110 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
