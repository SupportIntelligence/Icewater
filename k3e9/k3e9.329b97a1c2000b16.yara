
rule k3e9_329b97a1c2000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.329b97a1c2000b16"
     cluster="k3e9.329b97a1c2000b16"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce emailworm"
     md5_hashes="['129584dada47ee2ef2548acbb67fd780','1526197591df0a6ed6870fb42031be56','fe9678561032eaf3fd4f1ad72957a80a']"

   strings:
      $hex_string = { 6ef943864408598f5a74d904adde25ac1e11499e3aad0a4ab560fded0df1fe5e35064e93819b24d7f7cc88e41663f41bfbeb46aedf9520bfbb916a157d038a57 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
