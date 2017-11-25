
rule n3fd_0842892c5ba31114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fd.0842892c5ba31114"
     cluster="n3fd.0842892c5ba31114"
     cluster_size="141"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo backdoor"
     md5_hashes="['02731b186ee14063c20693d598e3796a','07713ba7e8ae10203c742dba54ef4a19','1fb4f46df1a79cfae148c326ecf1ddb9']"

   strings:
      $hex_string = { 6c696e67006765745f436f6e7665727465727300446573657269616c697a65006335313661323031616166616435313833316437376363613436343264396232 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
