
rule n3e9_1311e535dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1311e535dee30932"
     cluster="n3e9.1311e535dee30932"
     cluster_size="30"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['098a9fa0022d61800ca43eceb44f7466','287ecf1b4c80d5cc91559f5fed8abe71','b1089c59e8c126ea04c5ceba423e52f0']"

   strings:
      $hex_string = { 0b56b22474584d13184fa03363c4309f5a46aec765ca54d24bd5fc6e2ca110f503aa9979b18fe183db279dd81e21d052c5a794f282fe938a9a078b9131eaf16f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
