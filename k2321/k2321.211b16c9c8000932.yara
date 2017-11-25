
rule k2321_211b16c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.211b16c9c8000932"
     cluster="k2321.211b16c9c8000932"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol servstart ageneric"
     md5_hashes="['32a2b51b366dc8e9a262686e137e729b','924fb589bbe9b118fac9fcf19aa7735f','ea49757e49a4e8417473076ccbbf1478']"

   strings:
      $hex_string = { ee1646b56d31e3becf97866b3635a1ecf676222e0e3ec2db51e9b0921713f371a4b77790999594825c14eb5ffc5eb1981e09c3967d247a21d9a31ec0fbe89c87 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
